"""Keep actual async WUA comparisons strict around generated job metadata."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_win_updates_async_capture import compare_phases, compare_record


def _record() -> dict[str, Any]:
    record: dict[str, Any] = {"workspace": r"C:\Temp\owned-updates"}
    caches = {}
    for phase, pid in (("native", 11), ("original", 22)):
        launch = {
            "ansible_job_id": f"j100.{pid}",
            "ansible_async_watchdog_pid": pid,
            "results_file": record["workspace"] + f"\\cache\\j100.{pid}",
            "started": True,
            "finished": False,
            "changed": False,
            "failed": False,
        }
        status = dict(
            launch,
            finished=True,
            attempts=pid,
            found_update_count=0,
            updates={},
            filtered_updates={
                "update-id": {"filtered_reasons": ["reject_list", "hidden"]}
            },
        )
        record[f"{phase}_launch"] = launch
        record[f"{phase}_status"] = status
        record[f"{phase}_identity"] = {
            "stdout": json.dumps(
                {
                    "launch": launch,
                    "worker": {"pid": pid, "created": 1234, "alive": True},
                }
            )
        }
        body = {key: value for key, value in status.items() if key != "attempts"}
        caches[launch["ansible_job_id"]] = {
            "json": body,
            "body_base64": base64.b64encode(json.dumps(body).encode()).decode(),
        }
    record["observation"] = {"stdout": json.dumps({"cache_records": caches})}
    return record


def test_complete_public_types_order_and_raw_bytes_are_preserved() -> None:
    record = _record()
    original = deepcopy(record)
    compare_record(record)
    assert record == original


def test_independently_restored_owned_workspaces_keep_whole_results() -> None:
    record = _record()
    caches = json.loads(record.pop("observation")["stdout"])["cache_records"]
    original_workspace = record.pop("workspace")
    for phase in ("native", "original"):
        workspace = original_workspace + "-" + phase
        record[f"{phase}_workspace"] = workspace
        identifier = record[f"{phase}_launch"]["ansible_job_id"]
        for suffix in ("launch", "status"):
            record[f"{phase}_{suffix}"]["results_file"] = (
                workspace + "\\cache\\" + identifier
            )
        identity = json.loads(record[f"{phase}_identity"]["stdout"])
        identity["launch"] = record[f"{phase}_launch"]
        record[f"{phase}_identity"]["stdout"] = json.dumps(identity)
        body = caches[identifier]["json"]
        body["results_file"] = workspace + "\\cache\\" + identifier
        caches[identifier]["body_base64"] = base64.b64encode(
            json.dumps(body).encode()
        ).decode()
        record[f"{phase}_observation"] = {
            "stdout": json.dumps({"cache_records": {identifier: caches[identifier]}})
        }
    before = deepcopy(record)
    compare_record(record)
    assert record == before


@pytest.mark.parametrize(
    "change", ["counter", "pid", "path", "birth", "value", "order", "cache"]
)
def test_unproved_job_or_cache_and_public_differences_are_rejected(change: str) -> None:
    record = _record()
    native = record["native_status"]
    if change == "counter":
        native["attempts"] = True
    elif change == "pid":
        native["ansible_async_watchdog_pid"] = 11.0
    elif change == "path":
        native["results_file"] = r"C:\unowned\j100.11"
    elif change == "value":
        native["found_update_count"] = False
    elif change == "order":
        native["filtered_updates"]["update-id"]["filtered_reasons"].reverse()
    elif change == "birth":
        identity = json.loads(record["native_identity"]["stdout"])
        identity["worker"]["created"] = 0
        record["native_identity"]["stdout"] = json.dumps(identity)
    else:
        observation = json.loads(record["observation"]["stdout"])
        observation["cache_records"]["j100.11"]["json"]["changed"] = True
        record["observation"]["stdout"] = json.dumps(observation)
    with pytest.raises(AssertionError):
        compare_record(record)


def _phases(tmp_path: Path) -> tuple[Path, Path]:
    record = _record()
    cache = json.loads(record["observation"]["stdout"])["cache_records"]
    paths = []
    for name in ("native", "original"):
        phase = {
            "phase": name,
            "state": "downloaded",
            "kb": "KB123",
            "workspace": record["workspace"],
            "workspace_absent": True,
            "worker_absence": {"rc": 0},
            "recovery": {"rc": 0, "stdout": '{"restored":true}'},
            "global_before": {"stdout": '{"staging":[],"workers":[]}'},
            "global_after": {"stdout": '{"staging":[],"workers":[]}'},
        }
        for field in ("launch", "status", "identity"):
            phase[field] = record[f"{name}_{field}"]
        identifier = phase["launch"]["ansible_job_id"]
        phase["observation"] = {
            "stdout": json.dumps({"cache_records": {identifier: cache[identifier]}})
        }
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(phase), encoding="utf-8")
        paths.append(path)
    return paths[0], paths[1]


def test_public_only_reports_its_missing_cache_scope_without_mutating_raw(
    tmp_path: Path,
) -> None:
    native, original = _phases(tmp_path)
    phase = json.loads(native.read_text())
    phase["observation"] = {"rc": 1, "stdout": ""}
    phase["recovery"] = {"rc": 1, "stdout": ""}
    phase["workspace_absent"] = False
    native.write_text(json.dumps(phase))
    before = native.read_bytes(), original.read_bytes()
    assert compare_phases(native, original, public_only=True) == {
        "public_pairs": 1,
        "owned_cache_pairs": 0,
    }
    assert before == (native.read_bytes(), original.read_bytes())
    with pytest.raises(AssertionError):
        compare_phases(native, original)


@pytest.mark.parametrize("change", [None, "capture", "workspace", "exit", "holder"])
def test_separate_source_closure_requires_its_exact_raw_capture_and_process_exit(
    tmp_path: Path,
    change: str | None,
) -> None:
    native, original = _phases(tmp_path)
    phase = json.loads(original.read_text())
    phase.pop("workspace_absent")
    phase.pop("global_after")
    original.write_text(json.dumps(phase))
    closure = {
        "original_capture": deepcopy(phase),
        "workspace": phase["workspace"],
        "workspace_absent": True,
        "global_after": {"stdout": '{"staging":[],"workers":[]}'},
        "process": {
            "rc": 0,
            "stdout": json.dumps(
                {
                    "pinned_process_exit_confirmed": change != "exit",
                    "after": {
                        "holders": [1] if change == "holder" else [],
                        "processes": [],
                    },
                }
            ),
        },
    }
    if change == "capture":
        closure["original_capture"]["status"]["found_update_count"] = 5
    if change == "workspace":
        closure["workspace"] = r"C:\unrelated"
    closure_path = tmp_path / "closure.json"
    closure_path.write_text(json.dumps(closure))
    before = original.read_bytes()
    if change is None:
        assert compare_phases(native, original, original_closure_path=closure_path) == {
            "pairs": 1
        }
    else:
        with pytest.raises(AssertionError):
            compare_phases(native, original, original_closure_path=closure_path)
    assert original.read_bytes() == before
