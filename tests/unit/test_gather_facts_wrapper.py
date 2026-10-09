"""Check core's forced zero fact-gathering execution limit at the real argv ABI."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The private argv boundary is required by the installed Ansible action API.
# pylint: disable=protected-access

import json
from pathlib import Path
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.mark.parametrize("limit", [0, 30])
def test_core_parallel_limit_is_recorded_without_changing_startup_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: int
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    wrapper: Any = load_module(
        HELPER.parent / "legacy_windows_async_wrapper.py", "parallel_wrapper"
    )
    monkeypatch.setattr(wrapper, "__file__", str(tmp_path / "wrapper.py"))
    monkeypatch.setenv("ANSIBLE_ASYNC_DIR", str(tmp_path / "cache"))
    module = str(tmp_path / "setup.py")
    _directory, request, _cache, _job = wrapper._request(
        ["j1", str(limit), "false", module, "python", module, "args.json"], 5
    )
    record = json.loads(Path(request).read_text(encoding="utf-8-sig"))
    assert record["timeout"] == limit and record["startup_timeout"] == 5


@pytest.mark.parametrize("limit,startup", [(-1, 5), (30, 0), (0, 0)])
def test_invalid_limits_fail_before_creating_any_protocol_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limit: int, startup: int
) -> None:
    monkeypatch.syspath_prepend(str(HELPER.parent))
    wrapper: Any = load_module(
        HELPER.parent / "legacy_windows_async_wrapper.py", "invalid_parallel_wrapper"
    )
    monkeypatch.setattr(wrapper, "__file__", str(tmp_path / "wrapper.py"))
    monkeypatch.setenv("ANSIBLE_ASYNC_DIR", str(tmp_path / "cache"))
    module = str(tmp_path / "setup.py")
    with pytest.raises(ValueError, match="startup deadline must be positive"):
        wrapper._request(
            ["j1", str(limit), "false", module, "python", module, "args.json"], startup
        )
    assert not list(tmp_path.iterdir())
