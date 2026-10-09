"""Check whole paired Copy/Template Runas gates without accessing Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import copy
import importlib.util
import itertools
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

# Nix supplies PyYAML without typing metadata.
import yaml  # type: ignore[import-untyped]

# Read the installed pinned controller bootstrap as context, never copy it.
from ansible import __file__ as ansible_file  # type: ignore[import-untyped]

from scripts import verify_copy_template_runas_capture as verifier

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/integration/fixtures/copy_template_runas.py"


def _source_bootstrap(branch: int = 2) -> str:
    assert isinstance(ansible_file, str)
    source = (
        Path(ansible_file).parent / "executor/powershell/become_wrapper.ps1"
    ).read_text()
    blocks = re.findall(r"\$command (?:\+?=) @'\n(.*?)\n'@", source, re.S)
    assert len(blocks) == 3
    return "\n".join(
        line.strip()
        # PowerShell here-string concatenation inserts no separating newline.
        for line in (blocks[0] + blocks[branch]).splitlines()
        if line.strip()
    )


def _synthetic_tokens(row: dict[str, Any], directory: str, index: int) -> None:
    expected_sid = "S-1-5-18" if row["case"][0] == "system" else "requested-user"
    count = 2 if row["case"][2] == "create" else 1
    for side in ("native", "original"):
        observer = {"pid": 1000 + index, "created": 116444736000000000, "alive": True}
        start = {
            "observer": observer,
            "baseline": [],
            "started_epoch": 1.0,
            "observer_sid": "requested-user",
            "side": side,
            "workspace": directory,
            "python": [3, 4, 4],
        }
        records = []
        for offset in range(count):
            identity = {
                "pid": 2000 + offset,
                "created": 116444736015000000,
                "alive": True,
            }
            parent = {
                "pid": 3000 + offset,
                "created": 116444736010000000,
                "alive": True,
            }
            command = (
                directory + "\\staging\\ansible-tmp-test\\AnsiballZ_win_copy.py"
                if side == "native"
                else "powershell.exe -noni -nop -ex Bypass -e "
                + base64.b64encode(_source_bootstrap().encode("utf-16-le")).decode()
            )
            records.append(
                {
                    "identity": identity,
                    "sid": expected_sid,
                    "process": {
                        "Name": "python.exe" if side == "native" else "powershell.exe",
                        "ProcessId": identity["pid"],
                        "ParentProcessId": parent["pid"],
                        "CommandLine": command,
                    },
                    "parent_identity": parent,
                    "parent_sid": "requested-user",
                    "parent_process": {"ProcessId": parent["pid"]},
                    "observed_epoch": 1.8,
                }
            )
        row[side + "_observer_start"] = _observed(start)
        row[side + "_observer_stop"] = _observed(
            {
                "ready": start,
                "records": records,
                "races": [],
                "failure": None,
                "finished_epoch": 2.0,
                "observer": observer,
                "observer_closed": True,
                "valid": True,
                "expected_sid": expected_sid,
                "expected_workers": count,
            }
        )
        if row["case"][0] == "system":
            _synthetic_debug(row, side, start)


def _debug_snapshot(attributes: int) -> dict[str, Any]:
    return {
        "privileges": [{"luid": [20, 0], "attributes": attributes}],
        "debug_luid": [20, 0],
        "debug_attributes": attributes,
    }


def _synthetic_debug(row: dict[str, Any], side: str, start: dict[str, Any]) -> None:
    before, enabled = _debug_snapshot(0), _debug_snapshot(2)
    start["debug_privilege"] = {"before": before, "enabled": enabled}
    stop = json.loads(row[side + "_observer_stop"]["stdout"])
    stop["ready"] = start
    stop["debug_privilege"] = {
        "before": before,
        "enabled": enabled,
        "after": before,
        "token_closed": True,
    }
    row[side + "_observer_start"] = _observed(start)
    row[side + "_observer_stop"] = _observed(stop)


def _observed(value: Any) -> dict[str, Any]:
    return {"rc": 0, "stdout": json.dumps(value)}


def _synthetic_output(contents: dict[str, bytes], workflow: str) -> dict[str, Any]:
    output = {
        name: {
            "base64": base64.b64encode(data).decode(),
            "metadata": {"attributes": 32, "modification_time": 116444736015000000},
            "security": {
                "owner": "S-1-5-32-544",
                "sddl": "O:BAD:",
            },
        }
        for name, data in contents.items()
    }
    if workflow == "archive":
        for name in ("nested", "empty"):
            output[name] = {
                "metadata": {
                    "attributes": 16,
                    "modification_time": 116444736015000000,
                },
                "security": {
                    "owner": "S-1-5-32-544",
                    "sddl": "O:BAD:",
                },
            }
    return output


def _synthetic_pair(
    index: int,
    case: tuple[str, str, str],
    directory: Path,
    setup: dict[str, Any],
    contents: dict[str, bytes],
) -> dict[str, Any]:
    output = _synthetic_output(contents, case[1])
    staging = setup["staging_inventory"]
    before = {
        **setup,
        "output": output if case[2] in ("repeat", "check_existing") else {},
        "time": 1.0,
        "staging": sorted(staging),
        "staging_inventory": staging,
    }
    after = {**before, "output": {} if case[2] == "check_new" else output, "time": 2.0}
    public = {
        "failed": False,
        "changed": case[2] in ("create", "check_new"),
        "src": "/literal/controller/input",
        "dest": "C:\\owned\\output",
    }
    row: dict[str, Any] = {
        "case": list(case),
        "native": dict(public),
        "original": dict(public),
        "before_native": _observed(before),
        "before_original": _observed(before),
        "after_native": _observed(after),
        "after_original": _observed(after),
    }
    if case[1] == "template":
        for side in ("native", "original"):
            row[side]["src"] = str(directory / f"render-{side}-{index}" / "basic.j2")
            row["rendered_" + side] = {"stat": {"exists": False}}
        if case[2] in ("create", "check_new"):
            observed = json.loads(row["after_original"]["stdout"])
            child = f"ansible-tmp-synthetic-{index}"
            observed["staging"] = sorted([*staging, child])
            observed["staging_inventory"] = {
                **staging,
                child: {
                    "metadata": {
                        "attributes": 16,
                        "modification_time": 116444736015000000,
                    },
                    "security": {"owner": "S-1-5-32-544", "sddl": "literal"},
                },
            }
            row["after_original"] = _observed(observed)
    _synthetic_tokens(row, "C:\\OwnedTransfer", index)
    return row


@pytest.fixture(name="workflow_fixture")
def _workflow_fixture() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "owned_copy_template_fixture", FIXTURE
    )
    assert spec is not None and spec.loader is not None
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    return fixture


@pytest.fixture(name="capture")
def _capture(tmp_path: Path, workflow_fixture: ModuleType) -> dict[str, Any]:
    """Construct complete typed synthetic comparisons, never runtime evidence.

    :param tmp_path: Pytest's exclusive local filesystem scope.
    :param workflow_fixture: The maintained fixture's pure data generation.
    :returns: Twenty-four complete public/content/ownership pairs.
    """
    directory = tmp_path / "copy-template-runas-local-test"
    directory.mkdir()
    global_state = {"python": [3, 4, 4], "profiles": {"loaded": ["example"]}}
    protected = {"base64": "AAH/", "mtime": 0, "owner": "protected"}
    setup = {
        "source": protected,
        "sentinel": protected,
        "global": global_state,
        "staging": [],
        "staging_inventory": {},
    }
    result: dict[str, Any] = {
        "setup": _observed(setup),
        "results": [],
        "controller_temp_root": str(directory),
        "controller_workspace": {"path": str(tmp_path / "absent-sources")},
        "controller_before": _observed({"input": {"mtime": 0, "sha256": "x"}}),
        "controller_after": _observed({"input": {"mtime": 0, "sha256": "x"}}),
        "staging_before": _observed([]),
        "staging_after": _observed([]),
        "identity": {"account": {"sid": "requested-user"}},
        "workspace": {"path": "C:\\OwnedTransfer"},
        "final_identity": {"account": {"sid": "requested-user"}},
        "recovery": _observed({**setup, "workspace_absent": True}),
    }
    cases = itertools.product(
        ("user", "system"),
        ("file", "archive", "template"),
        ("create", "repeat", "check_existing", "check_new"),
    )
    staging: dict[str, Any] = {}
    for index, case in enumerate(cases):
        # Only the maintained fixture's data is reused, not its Windows APIs.
        contents = workflow_fixture._content(  # pylint: disable=protected-access
            case[1]
        )
        result["results"].append(
            _synthetic_pair(
                index,
                case,
                directory,
                {**setup, "staging_inventory": staging},
                contents,
            )
        )
        staging = json.loads(result["results"][-1]["after_original"]["stdout"])[
            "staging_inventory"
        ]
    final = json.loads(result["results"][-1]["after_original"]["stdout"])
    result["recovery"] = _observed({**final, "workspace_absent": True})
    return result


def test_seeded_archive_directory_dates_are_literal(
    tmp_path: Path, workflow_fixture: ModuleType
) -> None:
    for name in ("native", "original"):
        directory = tmp_path / name
        # Exercise maintained fixture generation, not a reimplemented seed.
        workflow_fixture._write_content(  # pylint: disable=protected-access
            str(directory), "archive"
        )
        assert all(path.stat().st_mtime == 946782244 for path in directory.rglob("*"))


def test_template_seed_matches_real_controller_delegation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, workflow_fixture: ModuleType
) -> None:
    # Pytest exposes the maintained neighboring fixture as a top-level module.
    fixture = importlib.import_module("test_win_template_action")
    action, state = fixture._action(  # pylint: disable=protected-access
        monkeypatch,
        tmp_path,
        {
            "src": str(ROOT / "tests/integration/templates/win_template/basic.j2"),
            "dest": "C:\\owned\\basic.txt",
        },
    )
    state.variables = {"template_value": "Café 雪 \\path % ! &"}
    action.run(task_vars=state.variables)
    # The target seed must be the exact bytes produced by this public action.
    assert (
        state.calls[0]["content"]
        == workflow_fixture._content("template")[  # pylint: disable=protected-access
            "basic.txt"
        ]
    )


def test_all_twenty_four_typed_pairs_and_capture_immutability(
    capture: dict[str, Any],
) -> None:
    original = copy.deepcopy(capture)
    assert verifier.verify_capture(capture) == 24
    assert capture == original


def _selected_capture(
    capture: dict[str, Any], indices: list[int], workflow_fixture: ModuleType
) -> dict[str, Any]:
    selected = copy.deepcopy(capture)
    selected["case_indices"], selected["results"] = indices, []
    setup = json.loads(selected["setup"]["stdout"])
    staging: dict[str, Any] = {}
    for index in indices:
        case = tuple(capture["results"][index]["case"])
        # Use the maintained data, never invoke its Windows-only observations.
        contents = workflow_fixture._content(  # pylint: disable=protected-access
            case[1]
        )
        row = _synthetic_pair(
            index,
            case,
            Path(capture["controller_temp_root"]),
            {**setup, "staging_inventory": staging},
            contents,
        )
        selected["results"].append(row)
        staging = json.loads(row["after_original"]["stdout"])["staging_inventory"]
    final = json.loads(selected["results"][-1]["after_original"]["stdout"])
    selected["recovery"] = _observed({**final, "workspace_absent": True})
    return selected


@pytest.mark.parametrize(
    "indices", [[9], [0, 4, 5, 6, 8, 9, 10, 11, 12, 16, 17, 18, 20, 21, 22, 23]]
)
def test_bounded_selected_pairs_are_strictly_verified(
    capture: dict[str, Any], workflow_fixture: ModuleType, indices: list[int]
) -> None:
    selected = _selected_capture(capture, indices, workflow_fixture)
    assert verifier.verify_capture(selected, indices) == len(indices)
    with pytest.raises(AssertionError):
        verifier.verify_capture(selected)


@pytest.mark.parametrize("corruption", [None, "planned", "terminal", "count"])
def test_retained_user_prefix_requires_exact_interrupted_system_record(
    capture: dict[str, Any], workflow_fixture: ModuleType, corruption: str | None
) -> None:
    indices = [0, 4, 5, 6, 8, 9, 10, 11]
    retained = _selected_capture(capture, indices, workflow_fixture)
    retained["case_indices"] = indices + [12, 16, 17, 18, 20, 21, 22, 23]
    retained["latest_native_observer_stop"] = {
        "rc": 3,
        "failed": True,
        "stdout": json.dumps(
            {
                "valid": False,
                "observer_closed": True,
                "expected_sid": "S-1-5-18",
                "expected_workers": 2,
                "records": [],
                "races": [],
                "failure": "PermissionError(13, 'Access is denied.', None, 5)",
            }
        ),
    }
    if corruption == "planned":
        retained["case_indices"] = indices
    elif corruption == "terminal":
        retained["latest_native_observer_stop"]["rc"] = 0
    elif corruption == "count":
        retained["results"].pop()
    if corruption is None:
        assert (
            verifier.verify_capture(retained, indices, retained_user_prefix=True) == 8
        )
    else:
        with pytest.raises(AssertionError):
            verifier.verify_capture(retained, indices, retained_user_prefix=True)


@pytest.mark.parametrize("index", [8, 9, 10, 11])
def test_source_template_requires_exact_phase_specific_scratch_inventory(
    capture: dict[str, Any], index: int
) -> None:
    row = capture["results"][index]
    before = json.loads(row["before_original"]["stdout"])
    after = json.loads(row["after_original"]["stdout"])
    if row["case"][2] in ("create", "check_new"):
        added = set(after["staging"]) - set(before["staging"])
        assert len(added) == 1
        child = added.pop()
        after["staging"].remove(child)
        del after["staging_inventory"][child]
    else:
        child = "ansible-tmp-unexpected-noop"
        after["staging"].append(child)
        after["staging"].sort()
        after["staging_inventory"][child] = {
            "metadata": {"attributes": 16},
            "security": {"owner": "S-1-5-32-544", "sddl": "literal"},
        }
    row["after_original"] = _observed(after)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


@pytest.mark.parametrize("indices", [[], [9, 9], [9, 8], [24], [-1], [True]])
def test_invalid_bounded_selection_is_rejected(
    capture: dict[str, Any], indices: list[int]
) -> None:
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture, indices)


@pytest.mark.parametrize("branch", [1, 2])
def test_source_selector_matches_literal_core_concatenation(branch: int) -> None:
    observer = verifier._OBSERVER  # pylint: disable=protected-access
    row = {
        "Name": "powershell.exe",
        "CommandLine": "powershell.exe -noni -nop -ex Bypass -e "
        + base64.b64encode(_source_bootstrap(branch).encode("utf-16-le")).decode(),
    }
    assert observer._selected(  # pylint: disable=protected-access
        row, "C:\\Owned", "original"
    )


def test_observer_journals_actual_enumeration_clock_and_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer = verifier._OBSERVER  # pylint: disable=protected-access
    calls: list[bool] = []
    ready = {"workspace": "C:\\Owned", "side": "original", "baseline": []}

    def rows(_connection: Any) -> list[dict[str, Any]]:
        """:returns: An empty mock snapshot after recording enumeration."""
        calls.append(True)
        return []

    monkeypatch.setattr(observer, "_rows", rows)
    monkeypatch.setattr(observer.os.path, "exists", lambda _path: bool(calls))
    clock = iter([1.1, 1.2, 2.0])
    monkeypatch.setattr(observer.time, "time", lambda: next(clock))
    monkeypatch.setattr(observer.time, "sleep", lambda _seconds: None)
    result = observer._collect(  # pylint: disable=protected-access
        None, {}, ready, "C:\\Owned\\observer-original-0"
    )
    assert result == {
        "ready": ready,
        "records": [],
        "races": [],
        "failure": None,
        "enumerations": [{"started_epoch": 1.1, "finished_epoch": 1.2, "count": 0}],
        "finished_epoch": 2.0,
    }


@pytest.mark.parametrize(
    "change", ["enabled", "unrelated", "restoration", "handle", "viewer"]
)
def test_system_privilege_and_ordinary_viewer_gates_are_literal(
    capture: dict[str, Any], change: str
) -> None:
    row = capture["results"][12]
    start = json.loads(row["native_observer_start"]["stdout"])
    stop = json.loads(row["native_observer_stop"]["stdout"])
    if change == "viewer":
        start["observer_sid"] = "S-1-5-18"
    elif change == "handle":
        stop["debug_privilege"]["token_closed"] = False
    elif change == "restoration":
        stop["debug_privilege"]["after"]["debug_attributes"] = 2
    else:
        state = stop["debug_privilege"]["enabled"]
        if change == "enabled":
            state["debug_attributes"] = 0
        else:
            state["privileges"].append({"luid": [99, 0], "attributes": 2})
        start["debug_privilege"]["enabled"] = state
    stop["ready"] = start
    row["native_observer_start"], row["native_observer_stop"] = _observed(
        start
    ), _observed(stop)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


def test_observer_spawn_closes_launcher_handles_without_stdio_redirects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workflow_fixture: ModuleType
) -> None:
    identity = {"pid": 51, "created": 700, "alive": True}
    ready = {"observer": identity, "workspace": str(tmp_path)}
    calls: list[dict[str, Any]] = []

    def spawn(arguments: list[str], **options: Any) -> SimpleNamespace:
        """Record the exact launch without starting a child.

        :param arguments: The owned Python observer command.
        :param options: Literal subprocess launch options.
        :returns: A mock child whose readiness file is already complete.
        """
        calls.append({"arguments": arguments, **options})
        (tmp_path / "observer-native-0-ready.json").write_text(
            json.dumps(ready), encoding="utf-8"
        )
        return SimpleNamespace(pid=51)

    monkeypatch.setattr(workflow_fixture.subprocess, "Popen", spawn)
    monkeypatch.setattr(
        workflow_fixture,
        "_process_namespace",
        lambda: {"_process": lambda _pid: identity},
    )
    assert (
        workflow_fixture._start_observer(  # pylint: disable=protected-access
            str(tmp_path), "native", 0
        )
        == ready
    )
    assert calls == [
        {
            "arguments": [
                sys.executable,
                str(tmp_path / "observer.py"),
                str(tmp_path),
                "native",
                "native-0",
            ],
            "creationflags": 0x1000000 | 8 | 512,
            "close_fds": True,
        }
    ]
    assert not (tmp_path / "observer-native-0-stdout").exists()
    assert not (tmp_path / "observer-native-0-stderr").exists()


@pytest.mark.parametrize("failure", [False, True])
def test_observer_child_owns_output_files_and_preserves_startup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: bool
) -> None:
    observer = verifier._OBSERVER  # pylint: disable=protected-access
    original = sys.stdout, sys.stderr

    def monitor(*_arguments: str) -> None:
        print("Café 雪", file=sys.stdout)
        print("owned stderr", file=sys.stderr)
        if failure:
            raise ValueError("retained startup failure")

    monkeypatch.setattr(observer, "_monitor", monitor)
    monkeypatch.setattr(
        sys, "argv", ["observer.py", str(tmp_path), "native", "native-0"]
    )
    assert observer._main() == int(failure)  # pylint: disable=protected-access
    assert (sys.stdout, sys.stderr) == original
    assert (tmp_path / "observer-native-0-stdout").read_text(
        encoding="utf-8"
    ) == "Café 雪\n"
    errors = (tmp_path / "observer-native-0-stderr").read_text(encoding="utf-8")
    assert errors.startswith("owned stderr\n")
    assert ("ValueError: retained startup failure" in errors) is failure


def test_observer_reused_pid_does_not_terminate_another_birth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workflow_fixture: ModuleType
) -> None:
    original = {"pid": 51, "created": 700, "alive": True}
    prefix = str(tmp_path / "observer-native-0")
    (tmp_path / "observer-state.json").write_text(
        json.dumps({"identity": original, "prefix": prefix}), encoding="utf-8"
    )
    Path(prefix + "-result.json").write_text(
        json.dumps({"records": []}), encoding="utf-8"
    )
    monkeypatch.setattr(
        workflow_fixture,
        "_process_namespace",
        lambda: {
            "_process": lambda _pid: {"pid": 51, "created": 701, "alive": True},
            "_kernel": lambda: pytest.fail("A reused PID must never be terminated"),
        },
    )
    # Call the maintained ownership cleanup; no Windows API executes here.
    result = workflow_fixture._stop_observer(  # pylint: disable=protected-access
        str(tmp_path), recover=True
    )
    assert result["observer"] == original and result["observer_closed"] is True


@pytest.mark.parametrize("birth", [700, 701])
def test_observer_recovery_uses_exact_live_handle_birth(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    workflow_fixture: ModuleType,
    birth: int,
) -> None:
    identity = {"pid": 51, "created": 700, "alive": True}
    prefix = str(tmp_path / "observer-native-0")
    (tmp_path / "observer-state.json").write_text(
        json.dumps({"identity": identity, "prefix": prefix}), encoding="utf-8"
    )
    Path(prefix + "-stderr").write_bytes(b"retained incomplete observer")
    terminated: list[int] = []

    def clocks(_handle: int, first: Any, *_rest: Any) -> bool:
        """Mock the native output pointers.

        :param first: The output pointer receiving the observed process birth.
        :param _rest: Unused additional native output pointers.
        :returns: True after writing the mocked native birth observation.
        """
        # ctypes passes this exact by-reference object to the native ABI.
        first._obj.value = birth  # pylint: disable=protected-access
        return True

    def terminate(handle: int, _exit: int) -> bool:
        """Mock termination without a Windows process.

        :param handle: Exact process handle selected by the maintained recovery.
        :returns: True after recording the handle to be terminated.
        """
        terminated.append(handle)
        return True

    kernel = SimpleNamespace(
        OpenProcess=lambda *_args: 99,
        GetProcessTimes=clocks,
        TerminateProcess=terminate,
        WaitForSingleObject=lambda *_args: 0,
        CloseHandle=lambda _handle: True,
    )
    monkeypatch.setattr(
        workflow_fixture,
        "_process_namespace",
        lambda: {
            "_process": lambda _pid: {**identity, "alive": not terminated},
            "_kernel": lambda: kernel,
        },
    )
    clock = iter([0.0, 20.0])
    monkeypatch.setattr(workflow_fixture.time, "monotonic", lambda: next(clock))
    if birth != identity["created"]:
        with pytest.raises(AssertionError):
            # The handle birth must agree before any termination is permitted.
            workflow_fixture._stop_observer(  # pylint: disable=protected-access
                str(tmp_path), recover=True
            )
        assert not terminated
    else:
        # Recover only this fixture's exact still-live observer process.
        result = workflow_fixture._stop_observer(  # pylint: disable=protected-access
            str(tmp_path), recover=True
        )
        assert terminated == [99] and result["observer_closed"] is True
    assert (tmp_path / "observer-state.json").exists()


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "sid",
        "parent",
        "birth",
        "baseline",
        "ambiguity",
        "scope",
        "bootstrap",
        "closure",
    ],
)
def test_live_worker_identity_corruption_is_rejected(
    capture: dict[str, Any], change: str
) -> None:
    row = capture["results"][12]
    side = "original" if change == "bootstrap" else "native"
    stop = json.loads(row[side + "_observer_stop"]["stdout"])
    record = stop["records"][0]
    if change == "missing":
        stop["records"].pop()
    elif change == "sid":
        record["sid"] = "connected-account-not-System"
    elif change == "parent":
        record["process"]["ParentProcessId"] = 999
    elif change == "birth":
        record["identity"]["created"] = 116444736000000000
    elif change == "baseline":
        stop["ready"]["baseline"] = [{"identity": record["identity"]}]
        row[side + "_observer_start"] = _observed(stop["ready"])
    elif change == "ambiguity":
        stop["records"][1]["parent_identity"] = record["parent_identity"]
        stop["records"][1]["parent_process"] = record["parent_process"]
        stop["records"][1]["process"]["ParentProcessId"] = record["parent_identity"][
            "pid"
        ]
    elif change in ("scope", "bootstrap"):
        record["process"]["CommandLine"] = "unowned-or-unrecognized-worker"
    else:
        stop["observer_closed"] = False
    row[side + "_observer_stop"] = _observed(stop)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


@pytest.mark.parametrize("field", ["started_epoch", "finished_epoch", "observed_epoch"])
@pytest.mark.parametrize("value", [float("inf"), True, 3.0])
def test_worker_observation_clocks_are_finite_floats_and_ordered(
    capture: dict[str, Any], field: str, value: float | bool
) -> None:
    row = capture["results"][12]
    stop = json.loads(row["native_observer_stop"]["stdout"])
    if field == "started_epoch":
        stop["ready"][field] = value
        row["native_observer_start"] = _observed(stop["ready"])
    elif field == "observed_epoch":
        stop["records"][0][field] = value
    else:
        stop[field] = value if value != 3.0 else 0.0
    row["native_observer_stop"] = _observed(stop)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


@pytest.mark.parametrize(
    "change", ["outside", "parent_escape", "basename", "exists", "recorded_exists"]
)
def test_template_source_qualification_is_exact(
    capture: dict[str, Any], tmp_path: Path, change: str
) -> None:
    row = capture["results"][8]
    if change == "outside":
        row["native"]["src"] = str(tmp_path / "outside" / "basic.j2")
    elif change == "parent_escape":
        row["native"]["src"] = str(
            Path(capture["controller_temp_root"]) / ".." / "outside" / "basic.j2"
        )
    elif change == "basename":
        row["native"]["src"] = str(Path(row["native"]["src"]).with_name("other.j2"))
    elif change == "exists":
        path = Path(row["native"]["src"])
        path.parent.mkdir()
        path.write_bytes(b"still owned")
    else:
        row["rendered_native"]["stat"]["exists"] = True
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "failed",
        "boolean",
        "public",
        "bytes",
        "owner",
        "attributes",
        "existing_mtime",
        "clock",
        "profile",
        "protected",
        "staging",
        "clock_type",
        "recovery",
        "controller",
    ],
)
def test_corrupted_public_effects_and_recovery_are_rejected(
    capture: dict[str, Any], change: str
) -> None:
    row = capture["results"][12]
    if change == "missing":
        capture["results"].pop()
    elif change in ("failed", "boolean", "public"):
        key, value = {
            "failed": ("failed", True),
            "boolean": ("changed", 1),
            "public": ("extra", "unmatched"),
        }[change]
        row["native"][key] = value
    elif change in ("staging", "recovery", "controller"):
        key, value = {
            "staging": ("staging_after", ["leak"]),
            "recovery": ("recovery", {"workspace_absent": False}),
            "controller": ("controller_after", {"changed": True}),
        }[change]
        capture[key] = _observed(value)
    else:
        if change == "existing_mtime":
            row = capture["results"][13]
        observed = json.loads(row["after_native"]["stdout"])
        entry = observed["output"]["single.bin"]
        if change == "bytes":
            entry["base64"] = "AAAA"
        elif change == "owner":
            entry["security"]["owner"] = "not-system"
        elif change == "attributes":
            entry["metadata"]["attributes"] = 1
        elif change in ("existing_mtime", "clock"):
            entry["metadata"]["modification_time"] = 0
        elif change == "profile":
            observed["global"]["profiles"] = {"changed": True}
        elif change == "clock_type":
            observed["time"] = 2
        else:
            observed["source"] = {"changed": True}
        row["after_native"] = _observed(observed)
    with pytest.raises(AssertionError):
        verifier.verify_capture(capture)


def test_maintained_selector_and_public_dispatch_remain_synchronous() -> None:
    path = ROOT / "tests/integration/vars/copy_template_runas.yml"
    values = yaml.safe_load(path.read_text())
    assert values["copy_template_runas_users"] == ["user", "system"]
    assert values["copy_template_runas_workflows"] == ["file", "archive", "template"]
    assert values["copy_template_runas_phases"] == [
        "create",
        "repeat",
        "check_existing",
        "check_new",
    ]
    tasks = (ROOT / "tests/integration/tasks/copy_template_runas_case.yml").read_text()
    for module in (
        "sustainablelobster.legacy_windows.win_copy:",
        "sustainablelobster.legacy_windows.win_template:",
        "ansible.windows.win_copy:",
        "ansible.windows.win_template:",
    ):
        assert module in tasks
    assert "async:" not in tasks and "failed_when: false" not in tasks
    assert "become_method: ansible.builtin.runas" in tasks


@pytest.mark.parametrize(
    "case_indices",
    [
        list(range(24)),
        [0, 4, 5, 6, 8, 9, 10, 11, 12, 16, 17, 18, 20, 21, 22, 23],
        [12, 16, 17, 18, 20, 21, 22, 23],
        [9],
    ],
)
def test_actual_controller_binding_and_complete_stdin_source(
    tmp_path: Path, case_indices: list[int]
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    integration = ROOT / "tests/integration"
    shadow = tmp_path / "project/tests/integration"
    shadow.mkdir(parents=True)
    (shadow / "fixtures").symlink_to(integration / "fixtures", target_is_directory=True)
    (tmp_path / "project/plugins").symlink_to(
        ROOT / "plugins", target_is_directory=True
    )
    # pylint: enable=duplicate-code
    binding = yaml.safe_load(
        (integration / "tasks/copy_template_runas_case.yml").read_text()
    )[0]
    (shadow / "binding.yml").write_text(
        yaml.safe_dump(
            [
                binding,
                {
                    "name": "Require exact effective inputs",
                    "ansible.builtin.assert": {
                        "that": [
                            "copy_template_runas_source == "
                            "expected_sources[copy_template_runas_case[1]]",
                            "copy_template_runas_destination == "
                            "expected_destinations[copy_template_runas_case[1]]",
                            "copy_template_runas_user == "
                            "expected_users[copy_template_runas_case[0]]",
                            "copy_template_runas_check == "
                            "(copy_template_runas_case[2] in ['check_existing', 'check_new'])",
                        ],
                    },
                },
            ]
        )
    )
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    program_task = {
        "name": "Compile the literal maintained stdin source before any guest call",
        "ansible.builtin.command": {
            "argv": [
                sys.executable,
                "-c",
                "import sys; compile(sys.stdin.read(), '<fixture>', 'exec')",
            ],
            "stdin": "{{ copy_template_runas_program }}",
        },
        "changed_when": False,
    }
    # pylint: enable=duplicate-code
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [str(integration / "vars/copy_template_runas.yml")],
            "vars": {
                "ansible_user": "RequestedUser",
                "copy_template_runas_case_indices": case_indices,
                "copy_template_runas_workspace": {"path": "C:\\OwnedFixture"},
                "copy_template_runas_controller": {"path": "/owned/controller"},
                "expected_sources": {
                    "file": "/owned/controller/single.bin",
                    "archive": "/owned/controller/tree/",
                    "template": "/owned/controller/single.bin",
                },
                "expected_destinations": {
                    "file": "C:\\OwnedFixture\\output\\single.bin",
                    "archive": "C:\\OwnedFixture\\output\\",
                    "template": "C:\\OwnedFixture\\output\\basic.txt",
                },
                "expected_users": {
                    "user": "RequestedUser",
                    "system": "NT AUTHORITY\\SYSTEM",
                },
            },
            "tasks": [
                program_task,
                {
                    "name": "Bind all 24 actual maintained case tuples locally",
                    "ansible.builtin.include_tasks": str(shadow / "binding.yml"),
                    "loop": "{{ copy_template_runas_case_indices | "
                    "map('extract', copy_template_runas_cases) | list }}",
                    "loop_control": {"loop_var": "copy_template_runas_case"},
                },
            ],
        }
    ]
    playbook = shadow / "local-binding.yml"
    playbook.write_text(yaml.safe_dump(play))
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            str(playbook),
        ],
        env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp")},
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    # pylint: enable=duplicate-code
    assert run.returncode == 0, run.stdout + run.stderr
