"""Fault-test literal environment witnesses and owned observation boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# pylint: disable=protected-access

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.verify_setup_environment_capture import _bitvise
from tests.unit.payload_support import ROOT, load_module


def _date(epoch: int) -> dict[str, Any]:
    instant = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return {
        "date": instant.strftime("%Y-%m-%d"),
        "day": instant.strftime("%d"),
        "hour": instant.strftime("%H"),
        "minute": instant.strftime("%M"),
        "month": instant.strftime("%m"),
        "second": instant.strftime("%S"),
        "time": instant.strftime("%H:%M:%S"),
        "year": instant.strftime("%Y"),
        "iso8601": instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iso8601_basic": instant.strftime("%Y%m%dT%H%M%S%f"),
        "iso8601_basic_short": instant.strftime("%Y%m%dT%H%M%S"),
        "iso8601_micro": instant.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "weekday": instant.strftime("%A"),
        "weekday_number": str((instant.weekday() + 1) % 7),
        "weeknumber": instant.strftime("%W"),
        "tz": "UTC",
        "tz_offset": "+00:00",
        "epoch_int": epoch,
        "epoch": str(epoch),
        "epoch_local": str(epoch),
    }


def _cli_capture() -> tuple[dict[str, Any], dict[str, Any]]:
    facts, rows = _witness()
    samples = {}
    for key, epoch, ticks in (
        ("preparation", 1699999990, 10000),
        ("before_native", 1699999990, 10000),
        ("between", 1700000000, 20000),
        ("after_original", 1700000005, 25000),
    ):
        samples[key] = {
            "stdout": json.dumps(
                {
                    "epoch": epoch,
                    "tick_milliseconds": ticks,
                    "physical_total_bytes": 4294967296,
                    "protected": {"literal": True},
                    "configuration": {
                        "timezone": [{"name": "TimeZoneKeyName", "value": "UTC"}]
                    },
                }
            )
        }
    capture: dict[str, Any] = dict(samples)
    for phase, epoch, uptime in (
        ("native", 1699999995, 15),
        ("original", 1700000002, 22),
    ):
        results = []
        for index in range(4):
            subsets = ["all"] if index < 2 else ["!all", "!min", "env"]
            public = {
                "ansible_env": dict(facts["ansible_env"]),
                "module_setup": True,
                "gather_subset": subsets,
            }
            if index < 2:
                public.update(
                    ansible_date_time=_date(epoch),
                    ansible_uptime_seconds=uptime,
                    ansible_lastboot="2023-11-14 22:13:00Z",
                    ansible_memtotal_mb=4096,
                    ansible_memfree_mb=1024,
                    ansible_swaptotal_mb=0,
                    ansible_pagefiletotal_mb=1024,
                    ansible_pagefilefree_mb=512,
                )
            results.append(
                {
                    "changed": False,
                    "ansible_facts": public,
                    "item": {
                        "subsets": subsets,
                        "check": bool(index % 2),
                        "environment": {} if index < 2 else {"Name": "literal"},
                    },
                }
            )
        capture[phase] = {"results": results}
    witness = {
        "failure": None,
        "python": "3.4.4 test",
        "witnesses": rows,
        "identity": {"pid": 1, "created": 1, "calibrated": True, "closed": True},
    }
    capture.update(
        recovery={
            "stdout": json.dumps(
                {
                    "restored": True,
                    "witness": witness,
                    "observation": json.loads(samples["after_original"]["stdout"]),
                }
            )
        },
        completed={
            "finished": True,
            "rc": 0,
            "stdout": '{"witness_stopped":true}',
            "ansible_job_id": "owned",
        },
        launch={"ansible_job_id": "owned", "results_file": "owned/cache"},
        cache_removed={"erased": "owned/cache"},
        staging_before={"stdout": "[]"},
    )
    return capture, {
        "workspace_absent": True,
        "staging_before": {"stdout": "[]"},
        "staging_after": {"stdout": "[]"},
    }


def test_standalone_verifier_from_unrelated_cwd_without_pythonpath(
    tmp_path: Path,
) -> None:
    capture, closure = _cli_capture()
    path = tmp_path / "retained.json"
    path.write_text(json.dumps(capture), encoding="utf-8")
    Path(str(path) + ".closure.json").write_text(json.dumps(closure), encoding="utf-8")
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/verify_setup_environment_capture.py"),
            str(path),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["pairs"] == 4
    assert result.stderr == ""


def test_play_uses_the_public_cache_interface_and_retains_requests_first() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/setup_environment.yml").read_text()
    )[0]
    block = play["tasks"][-1]
    launches = [task for task in block["block"] if task.get("async")]
    assert len(launches) == 1
    assert launches[0]["vars"]["ansible_async_dir"].endswith("\\cache")
    cleanup = block["always"]
    assert cleanup[0]["ansible.builtin.copy"]["dest"].endswith(".requests.json")
    statuses = [
        task
        for task in cleanup
        if "sustainablelobster.legacy_windows.async_status" in task
    ]
    assert len(statuses) == 2
    for task in statuses:
        assert set(task["sustainablelobster.legacy_windows.async_status"]) <= {
            "jid",
            "mode",
        }
        assert (
            task["vars"]["ansible_async_dir"]
            == launches[0]["vars"]["ansible_async_dir"]
        )
    assert [case["check"] for case in play["vars"]["setup_environment_cases"]] == [
        False,
        True,
        False,
        True,
    ]


@pytest.fixture(name="fixture")
def load_fixture() -> Any:
    """Load the actual Python 3.4 diagnostic fixture without contacting Windows.

    :returns: Imported maintained fixture.
    """
    return load_module(
        ROOT / "tests/integration/fixtures/setup_environment.py",
        "setup_environment_fixture",
    )


def test_decoder_retains_literal_case_unicode_and_trailing_backslashes(
    fixture: Any,
) -> None:
    block = "=C:=C:\\hidden\0MixedCase=Café 雪\\\0EMPTY=\0\0".encode("utf-16-le")
    assert fixture._decode_environment(block + b"\x00\xd8") == {
        "MixedCase": "Café 雪\\",
        "EMPTY": "",
    }


@pytest.mark.parametrize("block", [b"A\x00=\x00B\x00", b"A\x00=\x00\x00\xd8\0\0\0\0"])
def test_decoder_rejects_unterminated_or_invalid_utf16(
    fixture: Any, block: bytes
) -> None:
    with pytest.raises((ValueError, UnicodeDecodeError)):
        fixture._decode_environment(block)


def test_journal_requires_literal_owned_workspace(fixture: Any, tmp_path: Path) -> None:
    (tmp_path / "environment-journal.json").write_text(
        json.dumps({"workspace": "other"})
    )
    with pytest.raises(ValueError, match="literal workspace"):
        fixture._journal(str(tmp_path))


def test_changed_protected_value_is_rejected_before_clock_observation(
    fixture: Any, tmp_path: Path
) -> None:
    (tmp_path / "environment-journal.json").write_text(
        json.dumps(
            {
                "workspace": str(tmp_path),
                "before": {"value": "original"},
                "sentinel": {},
            }
        )
    )
    with pytest.raises(ValueError, match="protected registry"):
        fixture._observe(
            str(tmp_path),
            {
                "_protected_state": lambda: {"value": "changed"},
                "_file": lambda _path: {},
            },
        )


@pytest.mark.parametrize("created, expected", [(20, False), (21, True)])
def test_closure_distinguishes_original_live_pid_from_reuse(
    fixture: Any, created: int, expected: bool
) -> None:
    reader = SimpleNamespace(read=Mock(return_value={"created": created}))
    assert fixture._closed(reader, {42: {}}, {"pid": 42, "created": 20}) is expected
    assert fixture._closed(reader, {}, {"pid": 42, "created": 20}) is True


def test_failed_watch_retains_all_partial_identity_reads(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(fixture, "_journal", lambda _root: {})
    reader = SimpleNamespace(
        calibrate=lambda: {"pid": 42, "created": 20}, processes=lambda: {}
    )
    monkeypatch.setattr(fixture, "_ProcessReader", lambda: reader)

    def _fail(
        _root: str,
        _reader: Any,
        _initial: Any,
        witnesses: dict[int, Any],
        _errors: Any,
    ) -> None:
        witnesses[10] = {"pid": 10, "token": "literal"}
        raise ValueError("bounded diagnostic failure")

    monkeypatch.setattr(fixture, "_watch_processes", _fail)
    with pytest.raises(ValueError, match="bounded diagnostic failure"):
        fixture._watch(str(tmp_path))
    capture = json.loads((tmp_path / "witnesses.json").read_text())
    assert capture["failure"] == "bounded diagnostic failure"
    assert capture["witnesses"] == [{"pid": 10, "token": "literal"}]


def _witness() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    token = "0000002A-00000001-00000002-00000003"
    environment = {"BitviseSfsDll": token, "MixedCase": "雪\\"}
    facts = {
        "ansible_env": {key: value.rstrip("\\") for key, value in environment.items()}
    }
    row = {
        "token": token,
        "environment": environment,
        "created": 100,
        "pid": 99,
        "parent_pid": 42,
        "ancestry": [
            {"pid": 99, "parent_pid": 42, "name": "python.exe"},
            {"pid": 42, "parent_pid": 1, "name": "execs.exe"},
            {"pid": 1, "parent_pid": 0, "name": "BvSshServer.exe"},
        ],
        "natural_exit": True,
    }
    return facts, [row]


def test_public_opaque_token_requires_full_block_identity_and_closed_birth() -> None:
    facts, rows = _witness()
    assert _bitvise(facts, rows) == {
        "pid": 99,
        "created": 100,
        "token": rows[0]["token"],
    }
    assert facts["ansible_env"]["BitviseSfsDll"].startswith("<independently")
    assert facts["ansible_env"]["MixedCase"] == "雪"


@pytest.mark.parametrize(
    "defect", ["token", "environment", "case", "owner", "parent", "closed", "birth"]
)
def test_no_format_only_or_prefix_only_opaque_qualification(defect: str) -> None:
    facts, rows = _witness()
    if defect == "token":
        rows[0]["token"] = "0000002A-00000001-00000002-00000004"
    elif defect == "environment":
        rows[0]["environment"]["MixedCase"] = "wrong"
    elif defect == "case":
        rows[0]["environment"]["MIXEDCASE"] = rows[0]["environment"].pop("MixedCase")
    elif defect == "owner":
        rows[0]["ancestry"][1]["name"] = "other.exe"
    elif defect == "parent":
        rows[0]["ancestry"][2]["name"] = "other.exe"
    elif defect == "closed":
        rows[0]["natural_exit"] = False
    else:
        rows[0]["created"] = True
    with pytest.raises(ValueError):
        _bitvise(facts, rows)
