"""Test genuine-search evidence gates and actual controller stdin binding."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from scripts import verify_win_updates_search_success_capture as verifier

ROOT = Path(__file__).resolve().parents[2]


def _observed(value: Any) -> dict[str, Any]:
    return {"rc": 0, "stdout": json.dumps(value), "stderr": ""}


@pytest.fixture(name="capture")
def synthetic_capture() -> dict[str, Any]:
    """Build typed synthetic observations, never runtime support evidence.

    :returns: One empty but completed provider/public pair with owned closure.
    """
    public = {
        "changed": False,
        "failed": False,
        "reboot_required": False,
        "rebooted": False,
        "found_update_count": 0,
        "installed_update_count": 0,
        "failed_update_count": 0,
        "updates": {},
        "filtered_updates": {},
    }
    catalogue = {
        "python": [3, 4, 4],
        "online": False,
        "server_selection": 2,
        "criteria": "IsInstalled = 0",
        "result_code": 2,
        "elapsed": 0.5,
        "updates": [],
    }
    identity = {"pid": 100, "created": 10, "alive": True}
    records = [
        {
            "side": side,
            "identity": dict(identity, pid=101 + index),
            "sid": "S-1-5-18",
            "time": 1.0,
        }
        for index, side in enumerate(("native", "original"))
    ]
    protected = {
        "sha256": "0" * 64,
        "attributes": 32,
        "mtime_ns": 100,
        "security": base64.b64encode(b"complete descriptor").decode(),
    }
    text = "Searching for updates to install with query 'IsInstalled = 0'\nFound 0 updates\n"
    log = {"text": text, "body_base64": base64.b64encode(text.encode()).decode()}
    workspace = r"C:\OwnedWorkspace"
    return {
        "mode": "paired",
        "inputs": copy.deepcopy(verifier.INPUTS),
        "native": copy.deepcopy(public),
        "original": copy.deepcopy(public),
        "catalogue_before": _observed(catalogue),
        "catalogue_after": _observed(catalogue),
        "workspace": {"path": workspace},
        "protected": _observed(protected),
        "diagnostics": _observed(
            {
                "workspace": workspace,
                "protected": protected,
                "logs": {"native.log": log, "original.log": log},
            }
        ),
        "monitor": _observed(
            {"identity": identity, "owners": [{"Sid": "S-1-5-18"}] * 2}
        ),
        "monitor_closed": _observed(
            {
                "monitor_identity": identity,
                "monitor_final": None,
                "records": records,
                "backends_closed": [
                    {"expected": row["identity"], "actual": None} for row in records
                ],
            }
        ),
        "global_before": _observed({"owned roots": []}),
        "global_after": _observed({"owned roots": []}),
        "cache_before": _observed({"complete synthetic cache": []}),
        "before": _observed(
            {
                "protected": {
                    "registry": [],
                    "python_executable": "literal executable",
                    "network": [],
                    "updates_policy": [],
                    "updates_au_policy": [],
                    "services": [
                        {"Name": name, "State": "Stopped"}
                        for name in ("wuauserv", "BITS", "TrustedInstaller")
                    ],
                }
            }
        ),
    }


def _verify(tmp_path: Path, capture: dict[str, Any]) -> dict[str, Any]:
    origin_path = tmp_path / "restored.json"
    if "cache_before_origin" not in capture:
        origin_path.write_text(
            json.dumps(
                {
                    "mode": "observe",
                    "absence": {"stat": {"exists": False}},
                    "cache_before": capture["cache_before"],
                    "after": capture["before"],
                }
            )
        )
        capture["cache_before_origin"] = {
            "path": str(origin_path),
            "sha256": hashlib.sha256(origin_path.read_bytes()).hexdigest(),
            "boundary": "completed rollback recovery before this attempt snapshot",
        }
    path = tmp_path / "capture.json"
    path.write_text(json.dumps(capture))
    return verifier.verify_capture(path)


def test_completed_empty_catalogue_is_a_real_success(
    tmp_path: Path, capture: dict[str, Any]
) -> None:
    assert _verify(tmp_path, capture) == {
        "whole_typed_public_pairs": 1,
        "actual_backend_births_closed": 2,
        "provider_catalogue_rows": 0,
        "cache_recovery_required_separately": True,
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("failed", True),
        ("changed", True),
        ("rebooted", True),
        ("reboot_required", 0),
        ("found_update_count", False),
        ("failed_update_count", 0.0),
        ("installed_update_count", 1),
    ],
)
def test_identically_corrupted_public_success_is_rejected(
    tmp_path: Path, capture: dict[str, Any], field: str, value: Any
) -> None:
    for side in ("native", "original"):
        capture[side][field] = value
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("result_code", 4),
        ("result_code", True),
        ("elapsed", float("inf")),
        ("elapsed", True),
        ("online", True),
        ("criteria", "IsInstalled = 1"),
        ("server_selection", 1),
    ],
)
def test_cached_provider_must_really_complete(
    tmp_path: Path, capture: dict[str, Any], field: str, value: Any
) -> None:
    row = json.loads(capture["catalogue_before"]["stdout"])
    row[field] = value
    capture["catalogue_before"] = _observed(row)
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


@pytest.mark.parametrize(
    "text",
    [
        "Found 0 updates\n",
        "Searching for updates to install with query 'IsInstalled = 0'\n",
        "Searching for updates to install with query 'IsInstalled = 0'\nFound 1 updates\n",
        "Searching for updates to install with query 'IsInstalled = 0'\n"
        "Found 0 updates\nAccepting EULA",
    ],
)
def test_empty_selection_without_completed_online_search_is_rejected(
    tmp_path: Path, capture: dict[str, Any], text: str
) -> None:
    diagnostics = json.loads(capture["diagnostics"]["stdout"])
    diagnostics["logs"]["native.log"] = {
        "text": text,
        "body_base64": base64.b64encode(text.encode()).decode(),
    }
    capture["diagnostics"] = _observed(diagnostics)
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


def test_whole_public_extra_fields_remain_literal(
    tmp_path: Path, capture: dict[str, Any]
) -> None:
    capture["native"]["unexpected"] = {"counter": 1}
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


def test_live_backend_or_nonfinite_clock_is_rejected(
    tmp_path: Path, capture: dict[str, Any]
) -> None:
    stopped = json.loads(capture["monitor_closed"]["stdout"])
    stopped["backends_closed"][0]["actual"] = stopped["records"][0]["identity"]
    capture["monitor_closed"] = _observed(stopped)
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)
    stopped["backends_closed"][0]["actual"] = None
    stopped["records"][0]["time"] = float("inf")
    capture["monitor_closed"] = _observed(stopped)
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


@pytest.mark.parametrize("extra", [False, True])
def test_repeated_backend_birth_cannot_be_counted_as_two_closed_workers(
    tmp_path: Path, capture: dict[str, Any], extra: bool
) -> None:
    stopped = json.loads(capture["monitor_closed"]["stdout"])
    worker = copy.deepcopy(stopped["records"][0])
    closure = copy.deepcopy(stopped["backends_closed"][0])
    if extra:
        stopped["records"].append(worker)
        stopped["backends_closed"].append(closure)
    else:
        worker["side"] = "original"
        stopped["records"][1] = worker
        stopped["backends_closed"][1] = closure
    capture["monitor_closed"] = _observed(stopped)
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


def test_reused_pid_with_a_different_birth_is_a_distinct_closed_worker(
    tmp_path: Path, capture: dict[str, Any]
) -> None:
    stopped = json.loads(capture["monitor_closed"]["stdout"])
    identity = dict(stopped["records"][0]["identity"], created=11)
    stopped["records"][1]["identity"] = identity
    stopped["backends_closed"][1]["expected"] = identity
    capture["monitor_closed"] = _observed(stopped)
    assert _verify(tmp_path, capture)["actual_backend_births_closed"] == 2


def test_retained_origin_is_not_relabelled_or_silently_replaced(
    tmp_path: Path, capture: dict[str, Any]
) -> None:
    _verify(tmp_path, capture)
    capture["cache_before_origin"]["boundary"] = "new per-operation scan"
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)
    capture["cache_before_origin"][
        "boundary"
    ] = "completed rollback recovery before this attempt snapshot"
    capture["cache_before_origin"]["sha256"] = "0" * 64
    with pytest.raises(AssertionError):
        _verify(tmp_path, capture)


def test_actual_controller_retains_the_complete_historical_baseline(
    tmp_path: Path,
) -> None:
    integration = ROOT / "tests/integration"
    original = yaml.safe_load(
        (integration / "win_updates_search_success.yml").read_text()
    )[0]
    baseline = tmp_path / "restored.json"
    cache = _observed({"full file bytes and identities": ["literal historical data"]})
    baseline.write_text(
        json.dumps(
            {
                "mode": "observe",
                "absence": {"stat": {"exists": False}},
                "cache_before": cache,
            }
        )
    )
    # Execute only the maintained controller tasks, not any target observer.
    tasks = [
        task
        for task in original["tasks"]
        if task["name"]
        in (
            "Read the retained complete post-rollback baseline on controller",
            "Require its complete recovered cache without calling it a new scan",
            "Retain the source capture hash and explicit observation boundary",
            "Preserve the baseline and its actual historical origin",
        )
    ]
    assert len(tasks) == 4
    tasks.append(
        {
            "name": "Require literal historical bytes and their actual boundary",
            "ansible.builtin.assert": {
                "that": [
                    "updates_search_cache_before == expected_cache",
                    "updates_search_cache_origin.path == updates_search_baseline_capture",
                    "updates_search_cache_origin.sha256 == expected_sha",
                    "updates_search_cache_origin.boundary == expected_boundary",
                ]
            },
        }
    )
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars": {
                "updates_search_mode": "paired",
                "expected_cache": cache,
                "updates_search_baseline_capture": str(baseline),
                "expected_sha": hashlib.sha256(baseline.read_bytes()).hexdigest(),
                "expected_boundary": "completed rollback recovery before this attempt snapshot",
            },
            "tasks": tasks,
        }
    ]
    path = tmp_path / "retention.yml"
    path.write_text(yaml.safe_dump(play))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            str(path),
        ],
        env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp")},
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_actual_controller_binding_compiles_the_complete_maintained_program(
    tmp_path: Path,
) -> None:
    integration = ROOT / "tests/integration"
    shadow = tmp_path / "project/tests/integration"
    shadow.mkdir(parents=True)
    (shadow / "fixtures").symlink_to(integration / "fixtures", target_is_directory=True)
    (tmp_path / "project/legacy_windows").mkdir()
    (tmp_path / "project/legacy_windows/plugins").symlink_to(
        ROOT / "legacy_windows/plugins", target_is_directory=True
    )
    play = [
        {
            "hosts": "localhost",
            "connection": "local",
            "gather_facts": False,
            "vars_files": [str(integration / "vars/win_updates_search_success.yml")],
            "tasks": [
                {
                    "name": "Compile complete source without executing any Windows observer",
                    "ansible.builtin.command": {
                        "argv": [
                            sys.executable,
                            "-c",
                            "import sys; compile(sys.stdin.read(), '<fixture>', 'exec')",
                        ],
                        "stdin": "{{ updates_search_program }}",
                    },
                    "changed_when": False,
                },
                {
                    "name": "Require the exact public nonservicing request",
                    "ansible.builtin.assert": {
                        "that": ["updates_search_inputs == expected_inputs"]
                    },
                },
            ],
            "vars": {"expected_inputs": verifier.INPUTS},
        }
    ]
    path = shadow / "binding.yml"
    path.write_text(yaml.safe_dump(play))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            str(path),
        ],
        env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "ansible-tmp")},
        check=False,
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stdout + result.stderr
