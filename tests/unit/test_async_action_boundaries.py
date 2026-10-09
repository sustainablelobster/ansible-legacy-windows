"""Compare dedicated action rejection with the installed core public contract."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests inspect the controller extension boundary, not Windows support.
# pylint: disable=protected-access

from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]

from plugins.action import win_copy, win_template


@pytest.mark.parametrize(
    "action_type", [win_copy.ActionModule, win_template.ActionModule]
)
@pytest.mark.parametrize("poll", [0, 1, 15])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("become", [None, SimpleNamespace(name="sudo")])
def test_async_rejection_matches_core_before_validation_or_allocation(
    action_type: Any, poll: int, check_mode: bool, become: Any
) -> None:
    # The pinned released Copy/Template actions delegate this rejection to core
    # before checking arguments or allocating controller/target temporary files.
    action = action_type.__new__(action_type)
    name = "sustainablelobster.legacy_windows." + action_type.__module__.split(".")[-1]
    action._task = SimpleNamespace(
        action=name,
        args={"src": None, "dest": None},
        async_val=30,
        poll=poll,
        check_mode=check_mode,
    )
    action._connection = SimpleNamespace(
        become=become, _shell=SimpleNamespace(tmpdir=None)
    )
    action._make_tmp_path = Mock(side_effect=AssertionError("Unexpected allocation"))
    action._transfer_file = Mock(side_effect=AssertionError("Unexpected transfer"))
    before = vars(action._task).copy()
    with pytest.raises(AnsibleActionFail) as reference:
        ActionBase.run(action)
    with pytest.raises(AnsibleActionFail) as actual:
        action.run()
    assert (
        str(actual.value)
        == str(reference.value)
        == (f"This action ({name}) does not support async.")
    )
    assert vars(action._task) == before
    assert action._connection._shell.tmpdir is None
    action._make_tmp_path.assert_not_called()
    action._transfer_file.assert_not_called()
