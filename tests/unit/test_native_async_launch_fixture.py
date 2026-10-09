"""Check the public launch fixture's effective conditions before Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.integration_selection import assert_local_selection
from tests.unit.payload_support import ROOT


@pytest.mark.parametrize("system", [False, True])
def test_fixture_resolves_service_account_and_connection_cases(
    tmp_path: Path, system: bool
) -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/native_async_launch.yml").read_text()
    )[0]
    variables = dict(play["vars"], native_async_launch_system=system)
    conditions = [
        "native_async_launch_cases | length == " + ("6" if system else "4"),
        "native_async_launch_cases[0].poll == 0",
        "native_async_launch_cases[1].poll == 1",
        "native_async_launch_cases[2].runas",
        "native_async_launch_cases[3].runas",
    ]
    if system:
        conditions += [
            "native_async_launch_cases[4].user == 'SYSTEM'",
            "native_async_launch_cases[5].user == 'SYSTEM'",
            "native_async_launch_cases[4].password is none",
            "native_async_launch_cases[5].password is none",
        ]
    assert_local_selection(tmp_path, variables, conditions, [])


@pytest.mark.parametrize(
    "poll,runas,account",
    [
        (0, False, "Account"),
        (1, False, "Account"),
        (0, True, "Account"),
        (1, True, "Account"),
        (0, True, "SYSTEM"),
        (1, True, "SYSTEM"),
    ],
)
def test_public_result_conditions_accept_each_supported_launch_case(
    tmp_path: Path, poll: int, runas: bool, account: str
) -> None:
    tasks: list[dict[str, Any]] = yaml.safe_load(
        (ROOT / "tests/integration/tasks/native_async_launch_public.yml").read_text()
    )
    conditions = [
        condition
        for task in tasks
        if "ansible.builtin.assert" in task
        for condition in (
            task["ansible.builtin.assert"]["that"]
            if isinstance(task["ansible.builtin.assert"]["that"], list)
            else [task["ansible.builtin.assert"]["that"]]
        )
    ]
    assert_local_selection(
        tmp_path,
        {
            "native_async_launch_case": {
                "poll": poll,
                "runas": runas,
                "account": account,
            },
            "native_async_launch_public_result": {
                "started": True,
                "finished": True,
                "rc": 0,
                "stdout": (
                    '{"marker":"café λ","cwd":"C:\\\\Task","user":"' + account + '"}'
                ),
            },
            "native_async_launch_workspace": {"path": r"C:\Task"},
            "native_async_launch_identity": {"account": {"account_name": "account"}},
            "native_async_launch_public_counter": {"content": "b25jZQo="},
        },
        conditions,
        [],
    )
