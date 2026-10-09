"""Exercise complete cache inspection and fail-closed parallel worker cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any, cast
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.integration_selection import assert_local_selection

_FIXTURE = Path(__file__).parents[1] / "integration/fixtures/setup_parallel.py"
_COMPARISON_PROGRAM = """
import json,sys,yaml
from ansible._internal._datatag._tags import TrustedAsTemplate
from ansible.template import Templar
with open(sys.argv[1],encoding='utf-8') as stream: play=yaml.safe_load(stream)[0]
block=next(task['block'] for task in play['tasks'] if 'block' in task)
assertions=next(task['ansible.builtin.assert']['that'] for task in block
                if 'ansible.builtin.assert' in task)
expression=next(item for item in assertions if 'to_json(sort_keys=true)' in item)
templar=Templar(variables=json.loads(sys.stdin.read()))
print(json.dumps(templar.template(TrustedAsTemplate().tag('{{ '+expression+' }}'))))
"""


@pytest.mark.parametrize(
    "native_facts,source_facts,native_warnings,source_warnings,expected",
    [
        ({"name": "literal"}, {"name": "literal"}, None, None, True),
        (
            {"name": "literal"},
            {"name": "literal"},
            ["Module sustainablelobster.legacy_windows.win_product_facts"],
            ["Module ansible.windows.win_product_facts"],
            True,
        ),
        (
            {"name": "sustainablelobster.legacy_windows.sentinel"},
            {"name": "ansible.windows.sentinel"},
            ["Module sustainablelobster.legacy_windows.win_product_facts"],
            ["Module ansible.windows.win_product_facts"],
            False,
        ),
        ({"number": 1}, {"number": 1.0}, None, None, False),
        ({"rows": [1, 2]}, {"rows": [2, 1]}, None, None, False),
        ({"name": "literal"}, {"name": "literal"}, ["different"], ["original"], False),
        ({"name": "literal"}, {"name": "literal"}, [], None, False),
    ],
)
def test_actual_core_comparison_qualifies_only_warnings(
    native_facts: dict[str, object],
    source_facts: dict[str, object],
    native_warnings: list[str] | None,
    source_warnings: list[str] | None,
    expected: bool,
) -> None:
    native: dict[str, object] = {"ansible_facts": native_facts, "changed": False}
    source: dict[str, object] = {"ansible_facts": source_facts, "changed": False}
    if native_warnings is not None:
        native["warnings"] = native_warnings
    if source_warnings is not None:
        source["warnings"] = source_warnings
    # Real core templating can populate pre-init plugin caches. A fresh process
    # exercises the maintained expression without changing other tests' loaders.
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _COMPARISON_PROGRAM,
            str(_FIXTURE.parent.parent / "setup_parallel.yml"),
        ],
        input=json.dumps(
            {
                "setup_parallel_native": native,
                "setup_parallel_source": source,
                "setup_parallel_compare": True,
            }
        ),
        text=True,
        capture_output=True,
        check=True,
    )
    assert json.loads(completed.stdout) is expected


@pytest.mark.parametrize("become", [False, True])
@pytest.mark.parametrize("compare", [False, True])
def test_parallel_fixture_selects_identity_and_source_comparison_explicitly(
    tmp_path: Path, become: bool, compare: bool
) -> None:
    play = yaml.safe_load(
        (_FIXTURE.parent.parent / "setup_parallel.yml").read_text(encoding="utf-8")
    )[0]
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    native = next(
        task for task in block if task.get("register") == "setup_parallel_native"
    )
    source = next(
        task for task in block if task.get("register") == "setup_parallel_source"
    )
    identity = next(
        task for task in block if task.get("register") == "setup_parallel_identity"
    )
    assert native["sustainablelobster.legacy_windows.gather_facts"]["parallel"]
    assert source["ansible.builtin.gather_facts"]["parallel"] is False
    assert source["when"] == "setup_parallel_compare | bool"
    assert native["become"] == identity["become"] == source["become"]
    assert native["become_user"] == identity["become_user"] == source["become_user"]
    assert "user" in play["vars"]["setup_parallel_subsets"]
    assert_local_selection(
        tmp_path,
        {
            **play["vars"],
            "setup_parallel_become": become,
            "setup_parallel_compare": compare,
            "expected_become": become,
            "expected_compare": compare,
        },
        [
            "setup_parallel_become | bool == expected_become",
            "setup_parallel_compare | bool == expected_compare",
            "'user' in setup_parallel_subsets",
        ],
        [],
    )


def _fixture(root: Path) -> dict[str, Any]:
    namespace = runpy.run_path(
        str(_FIXTURE),
        init_globals={
            "WMI_SOURCE": "",
            "SETUP_SOURCE": "_file = lambda path: {'sentinel': 'unchanged'}",
            "ASYNC_SOURCE": (
                "_protected = lambda: {'registry': 'unchanged', 'services': "
                "[{'Name': 'one', 'State': 'Running', 'StartMode': 'Auto'}]}"
            ),
        },
    )
    namespace = cast(dict[str, Any], namespace["_setup"].__globals__)
    namespace["_ASYNC"]["_process"] = Mock(return_value=None)
    namespace["_setup"](str(root))
    return namespace


def _job(root: Path, side: str, **changes: object) -> None:
    record = {
        "ansible_job_id": "j1.2",
        "ansible_async_watchdog_pid": 42,
        "finished": True,
    }
    record.update(changes)
    (root / side / "j1.2").write_text(json.dumps(record), encoding="utf-8-sig")


def test_cleanup_records_both_real_cache_pids_before_removing_records(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    for side in ("native-cache", "source-cache"):
        _job(tmp_path, side)
    result = fixture["_cleanup"](str(tmp_path))
    assert result["persistent_restored"] and result["protected"] == result["before"]
    assert {job["side"] for job in result["jobs"]} == {
        "native-cache",
        "source-cache",
    }
    assert all(
        job["result"]["ansible_async_watchdog_pid"] == 42 for job in result["jobs"]
    )
    assert not list((tmp_path / "native-cache").iterdir())
    assert not list((tmp_path / "source-cache").iterdir())


@pytest.mark.parametrize("pid", [True, None, "42", -1])
def test_invalid_cache_pid_is_not_used_as_process_evidence(
    tmp_path: Path, pid: object
) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache", ansible_async_watchdog_pid=pid)
    with pytest.raises(AssertionError):
        fixture["_jobs"](str(tmp_path))
    fixture["_ASYNC"]["_process"].assert_not_called()


def test_live_or_reused_numeric_pid_retains_cache_and_workspace(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache")
    fixture["_ASYNC"]["_process"].return_value = {
        "pid": 42,
        "created": 999,
        "alive": True,
    }
    fixture["time"] = Mock(monotonic=Mock(side_effect=[0, 36]))
    with pytest.raises(ValueError, match="still alive; retain workspace"):
        fixture["_cleanup"](str(tmp_path))
    assert (tmp_path / "native-cache/j1.2").is_file()
    assert (tmp_path / "parallel-journal.json").is_file()


def test_exact_prior_absence_is_not_requeried_as_a_numeric_pid(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache")
    prior = fixture["_observe"](str(tmp_path))
    process = fixture["_ASYNC"]["_process"]
    process.reset_mock()
    process.side_effect = AssertionError("An already absent worker cannot return")
    result = fixture["_cleanup"](str(tmp_path), prior)
    assert result["persistent_restored"]
    assert result["jobs"][0]["worker_exit_previously_confirmed"]
    process.assert_not_called()
    assert not list((tmp_path / "native-cache").iterdir())


@pytest.mark.parametrize("change", ["workspace", "missing", "result", "type", "pid"])
def test_changed_prior_absence_cannot_authorize_cache_cleanup(
    tmp_path: Path, change: str
) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache", counter=1)
    prior = fixture["_observe"](str(tmp_path))
    if change == "workspace":
        prior["workspace"] = str(tmp_path / "other")
    elif change == "missing":
        (tmp_path / "native-cache/j1.2").unlink()
    elif change == "type":
        _job(tmp_path, "native-cache", counter=1.0)
    elif change == "pid":
        _job(tmp_path, "native-cache", counter=1, ansible_async_watchdog_pid=43)
    else:
        _job(tmp_path, "native-cache", counter=2)
    with pytest.raises(ValueError, match="another workspace|caches changed"):
        fixture["_cleanup"](str(tmp_path), prior)
    assert (tmp_path / "parallel-journal.json").is_file()
    if change != "missing":
        assert (tmp_path / "native-cache/j1.2").is_file()


@pytest.mark.parametrize("earlier", ["unfinished", "live"])
def test_unfinished_or_live_prior_record_keeps_native_wait_guards(
    tmp_path: Path, earlier: str
) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache")
    prior = fixture["_observe"](str(tmp_path))
    if earlier == "unfinished":
        prior["jobs"][0]["result"]["finished"] = False
    else:
        prior["jobs"][0]["process"] = {"pid": 42, "created": 99, "alive": True}
    fixture["_ASYNC"]["_process"].return_value = {
        "pid": 42,
        "created": 99,
        "alive": True,
    }
    fixture["time"] = Mock(monotonic=Mock(side_effect=[0, 36]))
    with pytest.raises(ValueError, match="still alive; retain workspace"):
        fixture["_cleanup"](str(tmp_path), prior)
    assert (tmp_path / "native-cache/j1.2").is_file()


@pytest.mark.parametrize("failure", ["configuration", "sentinel", "staging", "extra"])
def test_changed_protection_or_unowned_files_prevent_cleanup(
    tmp_path: Path, failure: str
) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache")
    if failure == "configuration":
        fixture["_ASYNC"]["_protected"] = lambda: {
            "registry": "changed",
            "services": [{"Name": "one", "State": "Running", "StartMode": "Auto"}],
        }
    elif failure == "sentinel":
        fixture["_SETUP"]["_file"] = lambda _path: {"changed": True}
    else:
        extra = tmp_path / ("staging/unowned" if failure == "staging" else "unowned")
        extra.write_text("retain", encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture["_cleanup"](str(tmp_path))
    assert (tmp_path / "native-cache/j1.2").is_file()


def test_runtime_service_changes_remain_observed_without_claiming_stasis(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _job(tmp_path, "native-cache")
    fixture["_ASYNC"]["_protected"] = lambda: {
        "registry": "unchanged",
        "services": [{"Name": "one", "State": "Stopped", "StartMode": "Auto"}],
    }
    result = fixture["_cleanup"](str(tmp_path))
    assert result["persistent_restored"]
    assert result["before"]["configuration"]["services"][0]["State"] == "Running"
    assert result["protected"]["configuration"]["services"][0]["State"] == "Stopped"
