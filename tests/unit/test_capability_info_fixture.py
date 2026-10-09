"""Exercise read-only capability journaling and exact recovery gates."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller substitutes do not establish Windows execution support.
# pylint: disable=exec-used

import copy
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

# The Nix developer environment supplies PyYAML without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="fixture")
def capability_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Load journal definitions without opening a native library or provider.

    :param tmp_path: Private test workspace.
    :param monkeypatch: Scoped Windows imports and arguments.
    :returns: Fixture definitions and substituted native observations.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/capability_info_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["capability_info_fixture"]
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "capability_info_fixture.py", "exec"), namespace)
    namespace["supported"] = True
    namespace["catalogue"] = Mock(
        return_value={"Client": "Installed", "Server": "Not Present"}
    )
    namespace["pending"] = Mock(return_value={"CBS": None, "WU": None})
    namespace["services"] = Mock(
        return_value={
            "TrustedInstaller": {"Name": "TrustedInstaller", "State": "Running"}
        }
    )
    namespace["restore_service"] = Mock()
    return namespace


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_original_service_and_reboot_journal_is_durable_before_query(
    fixture: dict[str, Any],
) -> None:
    def _query() -> dict[str, str]:
        journal = fixture["read"]()
        assert not journal["complete"]
        assert journal["before"]["capabilities"] is None
        assert journal["before"]["services"]["TrustedInstaller"]["State"] == "Running"
        return {"Client": "Installed", "Server": "Not Present"}

    fixture["catalogue"].side_effect = _query
    result = fixture["setup"]()
    assert fixture["read"]()["complete"]
    assert fixture["read"]()["before"] == result["before"]


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_existing_journal_is_never_overwritten(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    path = Path(fixture["journal_path"])
    before = path.read_bytes()
    with pytest.raises(AssertionError):
        fixture["setup"]()
    assert path.read_bytes() == before


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_metadata_failure_keeps_service_journal_for_incomplete_recovery(
    fixture: dict[str, Any],
) -> None:
    fixture["catalogue"].side_effect = OSError("metadata unavailable")
    with pytest.raises(OSError, match="metadata unavailable"):
        fixture["setup"]()
    assert not fixture["read"]()["complete"]
    fixture["catalogue"].side_effect = None
    result = fixture["cleanup"]()
    assert result["restored"] and result["setup_incomplete"]
    assert Path(fixture["journal_path"]).exists()
    assert fixture["finalize"]()["finalized"]


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("change", ["name", "state", "reboot", "service"])
def test_unmodeled_native_change_retains_journal_and_cannot_finalize(
    fixture: dict[str, Any], change: str
) -> None:
    fixture["setup"]()
    if change == "name":
        fixture["catalogue"].return_value = {"Other": "Installed"}
    elif change == "state":
        fixture["catalogue"].return_value = {
            "Client": "Not Present",
            "Server": "Not Present",
        }
    elif change == "reboot":
        fixture["pending"].return_value = {"CBS": {}, "WU": None}
    else:
        altered = copy.deepcopy(fixture["services"].return_value)
        altered["TrustedInstaller"]["Name"] = "unrelated"
        fixture["services"].return_value = altered
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).exists()
    with pytest.raises(AssertionError):
        fixture["finalize"]()


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_wrong_workspace_journal_is_rejected_before_native_queries(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    record = fixture["read"]()
    record["workspace"] = "unowned"
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    fixture["catalogue"].reset_mock()
    with pytest.raises(AssertionError):
        fixture["cleanup"]()
    fixture["catalogue"].assert_not_called()


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_service_recovery_failure_keeps_durable_full_baseline(
    fixture: dict[str, Any],
) -> None:
    fixture["setup"]()
    before = Path(fixture["journal_path"]).read_bytes()
    fixture["restore_service"].side_effect = OSError("stop denied")
    with pytest.raises(OSError, match="stop denied"):
        fixture["cleanup"]()
    assert Path(fixture["journal_path"]).read_bytes() == before


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_verified_recovery_waits_for_full_service_gate_before_finalization(
    fixture: dict[str, Any],
) -> None:
    setup = fixture["setup"]()
    result = fixture["cleanup"]()
    assert result["after"] == setup["before"]
    assert Path(fixture["journal_path"]).exists()
    assert fixture["read"]()["verified"]
    fixture["finalize"]()
    assert not Path(fixture["journal_path"]).exists()


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_absent_provider_still_checks_native_services_and_reboot_state(
    fixture: dict[str, Any],
) -> None:
    fixture["supported"] = False
    fixture["catalogue"].return_value = None
    assert not fixture["setup"]()["supported"]
    assert fixture["cleanup"]()["restored"]
    assert fixture["finalize"]()["finalized"]


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_preexisting_pending_values_are_preserved_without_reboot_or_servicing(
    fixture: dict[str, Any],
) -> None:
    original = {"CBS": {"Pending": [["owned-by-windows"], 7]}, "WU": None}
    fixture["pending"].return_value = original
    assert fixture["setup"]()["before"]["pending"] == original
    assert fixture["cleanup"]()["after"]["pending"] == original
    assert fixture["finalize"]()["finalized"]


# pylint: enable=duplicate-code
