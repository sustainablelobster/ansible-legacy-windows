"""Keep classic DSC's owned fixture and effective case selection bounded."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Private fixture functions are the recovery boundaries under test.
# pylint: disable=protected-access

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.verify_win_dsc_capture import compare_record
from tests.unit.integration_selection import assert_local_selection
from tests.unit.payload_support import ROOT, load_module


def _clock_record() -> dict[str, Any]:
    result = {
        "changed": True,
        "verbose_test": [
            "[HOST]: LCM:  [ End    Test     ]  "
            "[[File]DirectResourceAccess] False in 0.0040 seconds.",
            "[HOST]: LCM:  [ End    Set      ]    in  0.0130 seconds.",
            "Time taken for configuration job to complete is 0.112 seconds",
        ],
        "verbose_set": [
            "[HOST]: LCM:  [ End    Set      ]  "
            "[[File]DirectResourceAccess]  in 0.0060 seconds."
        ],
    }
    return {
        "name": "measured clocks",
        "native": result,
        "original": deepcopy(result),
        "before_native": {"end": "2026-10-02 10:00:00.000000"},
        "after_native": {"start": "2026-10-02 10:00:01.000000"},
        "before_original": {"end": "2026-10-02 10:00:02.000000"},
        "after_original": {"start": "2026-10-02 10:00:03.000000"},
    }


def test_measured_clocks_are_bounded_without_changing_raw_results() -> None:
    record = _clock_record()
    record["original"]["verbose_test"][0] = record["original"]["verbose_test"][
        0
    ].replace("0.0040", "0.0080")
    original = deepcopy(record)
    assert compare_record(record) == 8
    assert record == original


@pytest.mark.parametrize(
    "replacement",
    [
        "[HOST]: LCM:  [ End    Test     ]  "
        "[[File]DirectResourceAccess] False in 1.0040 seconds.",
        "[HOST]: LCM:  [ End    Test     ]  "
        "[[File]DirectResourceAccess] False in NaN seconds.",
        "Time taken for configuration job to complete is -0.112 seconds",
    ],
)
def test_unbounded_or_unknown_duration_is_rejected(replacement: str) -> None:
    record = _clock_record()
    record["native"]["verbose_test"][0] = replacement
    record["original"]["verbose_test"][0] = replacement
    with pytest.raises(AssertionError):
        compare_record(record)


def test_verbose_order_and_nonclock_wording_remain_literal() -> None:
    record = _clock_record()
    record["native"]["verbose_test"].reverse()
    with pytest.raises(AssertionError):
        compare_record(record)
    record = _clock_record()
    record["native"]["verbose_test"][0] = record["native"]["verbose_test"][0].replace(
        "False", "True"
    )
    with pytest.raises(AssertionError):
        compare_record(record)


@pytest.mark.parametrize("change", ["field", "type", "other_stream"])
def test_unrelated_public_fields_and_types_remain_literal(change: str) -> None:
    record = _clock_record()
    if change == "field":
        record["native"]["reboot_required"] = False
    elif change == "type":
        record["native"]["changed"] = 1
    else:
        record["native"]["warnings"] = [
            "Time taken for configuration job to complete is 0.1 seconds"
        ]
        record["original"]["warnings"] = [
            "Time taken for configuration job to complete is 0.2 seconds"
        ]
    with pytest.raises(AssertionError):
        compare_record(record)


@pytest.fixture(name="fixture")
def fixture_module() -> Any:
    """Load the Windows fixture without running its native operations.

    :returns: Isolated fixture module.
    """
    return load_module(
        ROOT / "tests/integration/fixtures/win_dsc.py", "win_dsc_fixture"
    )


def test_journal_workspace_identity_is_required(fixture: Any, tmp_path: Path) -> None:
    fixture._write(str(tmp_path), {"workspace": str(tmp_path) + "-other"})
    with pytest.raises(AssertionError):
        fixture._read(str(tmp_path))


def test_credential_journal_requires_its_owned_workspace(tmp_path: Path) -> None:
    credential_fixture = load_module(
        ROOT / "tests/integration/fixtures/win_dsc_credentials.py",
        "win_dsc_credential_fixture",
    )
    credential_fixture._write(str(tmp_path), {"workspace": str(tmp_path) + "-other"})
    with pytest.raises(AssertionError):
        credential_fixture._read(str(tmp_path))


def test_credential_cleanup_refuses_unrelated_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    credential_fixture = load_module(
        ROOT / "tests/integration/fixtures/win_dsc_credentials.py",
        "win_dsc_credential_fixture",
    )
    credential_fixture._write(str(tmp_path), {"workspace": str(tmp_path)})
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_bytes(b"do not delete")
    monkeypatch.setattr(credential_fixture, "_security", lambda _path: "security")
    with pytest.raises(AssertionError):
        credential_fixture._cleanup(str(tmp_path))
    assert unrelated.read_bytes() == b"do not delete"


def test_credential_matrix_exercises_both_real_credential_properties() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_dsc_credentials.yml").read_text()
    )[0]
    cases = play["vars"]["dsc_credential_cases"]
    assert len(cases) == 9
    assert sum(bool(case.get("check")) for case in cases) == 3
    assert sum(bool(case.get("failed")) for case in cases) == 3
    quiet_cases = play["vars"]["dsc_credential_quiet_cases"]
    assert len(quiet_cases) == 2
    assert [case["methods"] for case in quiet_cases] == [["Test", "Set"], ["Test"]]
    assert all(case["fresh_credential"] for case in quiet_cases)
    assert not any(case["emit_secret_diagnostics"] for case in quiet_cases)
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    requests = [task for task in block if "ansible.builtin.include_tasks" in task]
    assert [task["vars"]["dsc_credential_property"] for task in requests] == [
        "Credential",
        "PsDscRunAsCredential",
        "Credential",
        "PsDscRunAsCredential",
    ]
    assert [task["loop"] for task in requests] == [
        "{{ dsc_credential_cases }}",
        "{{ dsc_credential_cases }}",
        "{{ dsc_credential_quiet_cases }}",
        "{{ dsc_credential_quiet_cases }}",
    ]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le", "utf-16-be"])
def test_credential_cache_scan_rejects_secret_without_echoing_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    credential_fixture = load_module(
        ROOT / "tests/integration/fixtures/win_dsc_credentials.py",
        "win_dsc_credential_fixture",
    )
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    cache = tmp_path / "System32" / "Configuration"
    cache.mkdir(parents=True)
    (cache / "cache.bin").write_bytes("private-test-secret".encode(encoding))
    with pytest.raises(ValueError, match="DSC cache exposes") as error:
        credential_fixture._cache_secrets(["private-test-secret"])
    assert "private-test-secret" not in str(error.value)


def test_effective_classic_dsc_matrix_selection(tmp_path: Path) -> None:
    """Prove Ansible's effective default matrix before any wrapper lab call."""
    integration = ROOT / "tests/integration"
    original = yaml.safe_load((integration / "win_dsc.yml").read_text())[0]
    variables = yaml.safe_load((integration / "vars/win_dsc.yml").read_text())
    expected = variables["win_dsc_cases"]
    assert len(expected) == 24
    assert len({case["name"] for case in expected}) == 24
    assert sum(bool(case.get("failed")) for case in expected) == 9
    assert sum(bool(case.get("check")) for case in expected) == 6
    assert_local_selection(
        tmp_path,
        {"expected": expected},
        ["win_dsc_cases == expected", "not win_dsc_compare"],
        [str(integration / path) for path in original["vars_files"]],
    )


def test_effective_classic_dsc_absence_selection() -> None:
    play = yaml.safe_load(
        (ROOT / "tests/integration/win_dsc_unavailable.yml").read_text()
    )[0]
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    request = block[0]
    assert request["loop"] == [False, True]
    assert request["check_mode"] == "{{ item }}"
    assert request["sustainablelobster.legacy_windows.win_dsc"] == {
        "resource_name": "File",
        "DestinationPath": r"C:\Windows\Temp\legacy-win-dsc-absent-engine",
        "Ensure": "Present",
    }
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/win_dsc_unavailable.yml").read_text()
    )
    assert (
        "assert not any(engines.values()), engines"
        in variables["win_dsc_absence_program"]
    )
