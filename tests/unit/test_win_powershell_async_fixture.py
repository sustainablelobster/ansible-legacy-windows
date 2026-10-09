"""Keep async script recovery fail-closed around live identities and artifacts."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import runpy
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest

_BINDING_PROGRAM = """
import json,sys,yaml
from ansible._internal._datatag._tags import TrustedAsTemplate
from ansible.template import Templar
with open(sys.argv[1],encoding='utf-8') as stream: tasks=yaml.safe_load(stream)
with open(sys.argv[2],encoding='utf-8') as stream: variables=yaml.safe_load(stream)
status_tasks=tasks+[child for task in tasks for child in task.get('block',[])]
assert sum('ansible.builtin.async_status' in task for task in status_tasks)==2
assert not any('ansible.windows.async_status' in task for task in status_tasks)
index,phase=int(sys.argv[3]),sys.argv[4]
data={'powershell_async_case':variables['powershell_async_cases'][index],
      'powershell_async_header':variables['powershell_async_header'],
      'powershell_async_workspace':{'path':r'C:\\Temp\\owned-async'},
      'powershell_async_index':index,'powershell_async_phase':phase,
      'playbook_dir':'/owned/tests/integration'}
expression=tasks[0]['ansible.builtin.set_fact']['powershell_async_params']
result=Templar(variables=data).template(TrustedAsTemplate().tag(expression))
print(json.dumps(result))
"""


@pytest.mark.parametrize("index", range(4))
@pytest.mark.parametrize("phase", ["native", "original"])
def test_actual_core_binds_all_eight_script_phases_before_guest_execution(
    index: int,
    phase: str,
) -> None:
    integration = Path(__file__).parents[1] / "integration"
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _BINDING_PROGRAM,
            str(integration / "tasks/win_powershell_async_phase.yml"),
            str(integration / "vars/win_powershell_async.yml"),
            str(index),
            phase,
        ],
        text=True,
        capture_output=True,
        check=True,
    )
    params = json.loads(completed.stdout)
    assert params["parameters"]["MarkerPath"] == (
        rf"C:\Temp\owned-async/owned-jobs/{index}-{phase}.pid"
    )
    assert params["parameters"]["ReleasePath"] == (
        rf"C:\Temp\owned-async/owned-jobs/{index}-{phase}.release"
    )
    if index in (0, 3):
        assert "path" not in params
        assert params["script"].startswith("param([string]$MarkerPath")
        assert "throw 'owned async release missing'" in params["script"]
    elif index == 1:
        assert "script" not in params and params["remote_src"] is True
        assert params["path"] == r"C:\Temp\owned-async/resources/remote-script.ps1"
        assert params["parameters"]["Text"] == "remote parameter λ"
    else:
        assert "script" not in params and "remote_src" not in params
        assert (
            params["path"]
            == "/owned/tests/integration/fixtures/win_powershell_async.ps1"
        )
        assert params["parameters"]["Text"] == "controller parameter λ"


def _fixture() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "integration/fixtures/win_powershell_async.py"
    return runpy.run_path(
        str(path),
        init_globals={
            "RESOURCE_SOURCE": "",
            "ASYNC_SOURCE": "",
            "WMI_SOURCE": "",
        },
    )


@pytest.mark.parametrize(
    "actual,expected",
    [
        (None, False),
        ({"pid": 42, "created": 1, "alive": False}, False),
        ({"pid": 42, "created": 2, "alive": True}, False),
        ({"pid": 42, "created": 1, "alive": True}, True),
    ],
)
def test_only_the_birth_pinned_live_owned_process_blocks_cleanup(
    actual: dict[str, object] | None,
    expected: bool,
) -> None:
    fixture = _fixture()
    assert (
        fixture["_owned_alive"](
            {
                "processes": [
                    {
                        "expected": {"pid": 42, "created": 1, "alive": True},
                        "actual": actual,
                    }
                ]
            }
        )
        is expected
    )


@pytest.mark.parametrize("field", ["live", "cache", "staging", "engine_scratch"])
def test_unclosed_owned_resources_retain_journal_without_cleanup(field: str) -> None:
    fixture = _fixture()
    globals_ = fixture["_cleanup"].__globals__
    state: dict[str, object] = {
        "processes": [],
        "cache": {"native": {}, "original": {}},
        "staging": [],
        "engine_scratch": [],
    }
    if field == "live":
        state["processes"] = [
            {"expected": {"created": 1}, "actual": {"created": 1, "alive": True}}
        ]
    elif field == "cache":
        state["cache"] = {"native": {"j1.2": "retained"}, "original": {}}
    else:
        state[field] = ["retained"]
    globals_["_observe"] = Mock(return_value=state)
    globals_["time"] = Mock(monotonic=Mock(side_effect=[0, 31]))
    cleanup = Mock()
    globals_["_RESOURCE"]["_cleanup"] = cleanup
    with pytest.raises((AssertionError, ValueError)):
        fixture["_cleanup"]("owned-root")
    cleanup.assert_not_called()
